"""
StegAnalyzer Pro — lokal backend (Etappe A–C)
=============================================
Serverer HTML-en din OG kjører tunge forensic-verktøy lokalt.

  /               -> templates/index.html (din v3.4.0)
  /api/tools      -> hvilke verktøy som faktisk er installert (helsesjekk)
  /api/analyze    -> kjør ETT verktøy på en opplastet fil, returner JSON
  /api/download/<job> -> last ned zip med utpakkede filer (binwalk/foremost)

Kjøres synkront med timeouts. Sikkerhetsherding (token, sandkasse, Docker)
kommer i Etappe D — dette er A–C.
"""

from flask import Flask, render_template, request, jsonify, send_file, abort
import analyzers as az

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB maks opplasting


@app.route("/")
def index():
    # Din StegAnalyzer-HTML ligger i templates/index.html
    return render_template("index.html")


@app.route("/api/tools")
def api_tools():
    # Broen i nettleseren bruker dette til å vite hvilke knapper som gir mening.
    return jsonify({"tools": az.check_tools()})


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    az.cleanup_old()  # enkel husholdning, ikke sikkerhet

    if "file" not in request.files:
        return jsonify({"error": "Ingen fil mottatt"}), 400

    tool = request.form.get("tool", "")
    passphrase = request.form.get("passphrase", "")

    available = az.check_tools()
    if tool not in available:
        return jsonify({"error": f"Ukjent verktøy: {tool}"}), 400
    if not available[tool]:
        # Verktøyet finnes ikke på serveren – svar pent i stedet for å krasje.
        return jsonify({
            "tool": tool, "ok": False,
            "output": f"{tool} er ikke installert på serveren.",
        }), 200

    job_id, path = az.save_upload(request.files["file"])
    try:
        if tool == "zsteg":
            res = az.run_zsteg(path)
        elif tool == "steghide":
            res = az.run_steghide(path, passphrase)
        elif tool == "binwalk":
            res = az.run_binwalk(path)
        elif tool == "foremost":
            res = az.run_foremost(path)
        elif tool == "stegexpose":
            res = az.run_stegexpose(path)
        else:
            res = {"tool": tool, "ok": False, "output": "Ikke støttet."}
    finally:
        # Slett den opplastede originalen med en gang; utpakkede filer
        # (i extracted/) ryddes av cleanup_old() senere.
        try:
            path.unlink()
        except OSError:
            pass

    return jsonify(res)


@app.route("/api/download/<job_id>")
def api_download(job_id):
    # Kun heksadesimal job-id -> ingen sti-traversal mulig.
    if not job_id.isalnum():
        abort(400)
    zpath = az.EXTRACT_DIR / f"{job_id}.zip"
    if not zpath.exists():
        abort(404)
    return send_file(zpath, as_attachment=True,
                     download_name=f"stegano_{job_id}.zip")


if __name__ == "__main__":
    # threaded=True  -> flere verktøy-kall kan kjøre samtidig (broen fyrer parallelt).
    # host="127.0.0.1" -> KUN denne maskinen. Bytt til "0.0.0.0" for gruppe-CTF
    #                     (da gjelder netsh-port-forwardingen din fra WSL2-guiden).
    app.run(host="127.0.0.1", port=5000, threaded=True)
