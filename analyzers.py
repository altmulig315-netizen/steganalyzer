"""
analyzers.py — verktøy-wrappere for StegAnalyzer-backenden.

Felles mal:
  * kjør uten shell (liste-form)  -> ingen shell-injection
  * timeout per verktøy           -> henger aldri
  * cap på returnert stdout       -> flommer ikke nettleseren
  * temp-filer med unik id        -> ingen kollisjon

Utpakkings-verktøy (binwalk, foremost) kjøres i tillegg med DISK-TAK:
en zip-bombe (bittesmå inn -> gigantisk ut) blir avbrutt og slettet FØR den
fyller disken din. Dette er krasj-vern for din egen maskin — ikke det samme
som tilgangsherding (token/Docker/rate-limit), som fortsatt er Etappe D.
"""

import os
import time
import uuid
import signal
import shutil
import zipfile
import subprocess
from pathlib import Path

from werkzeug.utils import secure_filename

BASE = Path(__file__).parent
UPLOAD_DIR = BASE / "uploads"
EXTRACT_DIR = BASE / "extracted"
UPLOAD_DIR.mkdir(exist_ok=True)
EXTRACT_DIR.mkdir(exist_ok=True)

TIMEOUT = 120                         # sekunder per verktøy
MAX_OUTPUT = 200_000                  # tegn stdout vi sender tilbake
CLEAN_AFTER = 3600                    # slett temp eldre enn 1 time
MAX_EXTRACT_BYTES = 500 * 1024 * 1024 # 500 MB disk-tak på utpakking

# StegExpose kjøres via Java: java -jar tools/StegExpose.jar <mappe>
STEGEXPOSE_JAR = BASE / "tools" / "StegExpose.jar"

# PATH-baserte verktøy (oppdages med `which`). StegExpose håndteres separat.
PATH_TOOLS = ["zsteg", "steghide", "binwalk", "foremost"]


# --------------------------------------------------------------------------- #
# Helsesjekk
# --------------------------------------------------------------------------- #
def check_tools():
    """Returner {verktoy: bool} for hva som faktisk er tilgjengelig."""
    found = {t: shutil.which(t) is not None for t in PATH_TOOLS}
    # StegExpose = Java finnes OG JAR-en ligger på plass
    found["stegexpose"] = bool(shutil.which("java")) and STEGEXPOSE_JAR.exists()
    return found


# --------------------------------------------------------------------------- #
# Felles hjelpere
# --------------------------------------------------------------------------- #
def _run(cmd, timeout=TIMEOUT, cwd=None):
    """Kjør en kommando trygt (ingen shell). Returner (returkode, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace",
            timeout=timeout, cwd=cwd,
        )
        return p.returncode, (p.stdout or "")[:MAX_OUTPUT], (p.stderr or "")[:MAX_OUTPUT]
    except subprocess.TimeoutExpired:
        return -1, "", f"Tidsavbrudd etter {timeout}s."
    except FileNotFoundError:
        return -2, "", "Verktøyet er ikke installert."


def _dir_size(path):
    """Total størrelse (bytes) av alt under path. 0 hvis path ikke finnes."""
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def _run_capped(cmd, cwd, watch_dir, timeout=TIMEOUT, max_bytes=MAX_EXTRACT_BYTES):
    """Kjør en utpakkings-kommando med BÅDE tids- og diskgrense.

    Poller størrelsen på watch_dir mens prosessen kjører. Vokser den forbi
    max_bytes (zip-bombe), drepes HELE prosess-gruppen (binwalk starter barn
    som 7z/tar) og vi rapporterer avbrudd.

    Returner (returkode, stdout, stderr, avbrutt_grunn|None).
    """
    try:
        p = subprocess.Popen(
            cmd, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace",
            start_new_session=True,  # egen prosess-gruppe -> kan drepe barna
        )
    except FileNotFoundError:
        return -2, "", "Verktøyet er ikke installert.", None

    start = time.time()
    aborted = None
    while True:
        if p.poll() is not None:
            break
        if time.time() - start > timeout:
            aborted = f"Tidsavbrudd etter {timeout}s."
            break
        if _dir_size(watch_dir) > max_bytes:
            aborted = (f"Avbrutt: utpakking passerte disk-taket "
                       f"({max_bytes // (1024 * 1024)} MB) — mulig zip-bombe.")
            break
        time.sleep(0.4)

    if aborted:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            out, err = p.communicate(timeout=5)
        except Exception:
            out, err = "", ""
        return -1, (out or "")[:MAX_OUTPUT], ((err or "") + "\n" + aborted)[:MAX_OUTPUT], aborted

    out, err = p.communicate()
    return p.returncode, (out or "")[:MAX_OUTPUT], (err or "")[:MAX_OUTPUT], None


def _zip_paths(paths, job_id, base):
    """Zip filer/mapper (relativt til base) -> extracted/<job>.zip.

    Returner (zip_path, [relative filnavn]) eller (None, []) hvis tomt.
    """
    base = Path(base)
    files = []
    for p in map(Path, paths):
        if p.is_dir():
            files += [f for f in p.rglob("*") if f.is_file()]
        elif p.is_file():
            files.append(p)
    if not files:
        return None, []

    zpath = EXTRACT_DIR / f"{job_id}.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for f in files:
            z.write(f, f.relative_to(base))
    return zpath, [str(f.relative_to(base)) for f in files]


def cleanup_old():
    """Slett temp eldre enn CLEAN_AFTER. Husholdning, ikke sikkerhet."""
    now = time.time()
    for d in (UPLOAD_DIR, EXTRACT_DIR):
        for p in d.iterdir():
            try:
                if now - p.stat().st_mtime > CLEAN_AFTER:
                    shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink()
            except OSError:
                pass


def save_upload(file_storage):
    """Lagre opplastet fil med unik id. Returner (job_id, path)."""
    job_id = uuid.uuid4().hex
    name = secure_filename(file_storage.filename or "upload.bin")
    path = UPLOAD_DIR / f"{job_id}_{name}"
    file_storage.save(path)
    return job_id, path


# --------------------------------------------------------------------------- #
# Verktøy-wrappere
# --------------------------------------------------------------------------- #
def run_zsteg(path):
    """zsteg -a  (kun PNG/BMP). LSB i alle kanaler/rekkefølger."""
    rc, out, err = _run(["zsteg", "-a", str(path)])
    text = out.strip() or err.strip() or "Ingen funn."
    return {"tool": "zsteg", "ok": rc == 0, "output": text}


def run_steghide(path, passphrase=""):
    """steghide extract (JPG/BMP/WAV/AU). Prøver angitt passphrase (tom = ingen)."""
    out_file = UPLOAD_DIR / f"{uuid.uuid4().hex}_steghide.out"
    rc, out, err = _run([
        "steghide", "extract",
        "-sf", str(path),
        "-p", passphrase,
        "-xf", str(out_file),
        "-f",
    ])

    if rc == 0 and out_file.exists():
        try:
            data = out_file.read_text(errors="replace")[:MAX_OUTPUT]
        except OSError:
            data = "(binærdata trukket ut)"
        finally:
            try:
                out_file.unlink()
            except OSError:
                pass
        return {"tool": "steghide", "ok": True, "output": f"Data trukket ut:\n{data}"}

    msg = (err or out).strip().lower()
    if "could not extract" in msg or "wrong pass" in msg or "steghide:" in msg:
        msg = "Ingen skjult data / feil passphrase."
    return {"tool": "steghide", "ok": False, "output": msg or "Ingen funn."}


def run_binwalk(path):
    """binwalk -e med disk-tak. Signaturskann + utpakking. Zipper utfallet."""
    job = uuid.uuid4().hex
    workdir = UPLOAD_DIR / f"{job}_bw"
    workdir.mkdir(exist_ok=True)
    target = workdir / Path(path).name
    shutil.copy(path, target)

    rc, out, err, aborted = _run_capped(
        ["binwalk", "-e", str(target)], cwd=str(workdir), watch_dir=str(workdir)
    )

    if aborted:
        # Rydd bort delvis utpakking UMIDDELBART (frigjør disk).
        for p in list(workdir.iterdir()):
            if p.name == target.name:
                continue
            shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)
        return {"tool": "binwalk", "ok": False,
                "output": (out.strip() + "\n\n" + aborted).strip()}

    # Mappenavn varierer mellom binwalk-versjoner -> ta ALT nytt utenom originalen.
    produced = [p for p in workdir.iterdir() if p.name != target.name]
    zip_path, files = _zip_paths(produced, job, base=workdir)

    result = {"tool": "binwalk", "ok": rc == 0,
              "output": out.strip() or err.strip() or "Ingen signaturer funnet."}
    if zip_path:
        result["download"] = f"/api/download/{job}"
        result["files"] = files
    return result


def run_foremost(path):
    """foremost med disk-tak. File carving via magiske bytes. Zipper funnene."""
    job = uuid.uuid4().hex
    outdir = UPLOAD_DIR / f"{job}_fm"  # foremost KREVER at mappa ikke finnes

    rc, out, err, aborted = _run_capped(
        ["foremost", "-i", str(path), "-o", str(outdir)],
        cwd=str(UPLOAD_DIR), watch_dir=str(outdir),
    )

    if aborted:
        shutil.rmtree(outdir, ignore_errors=True)
        return {"tool": "foremost", "ok": False,
                "output": (out.strip() + "\n\n" + aborted).strip()}

    zip_path, files = (None, [])
    if outdir.exists():
        carved = [p for p in outdir.iterdir() if p.name != "audit.txt"]
        zip_path, files = _zip_paths(carved, job, base=outdir)

    result = {"tool": "foremost", "ok": rc == 0,
              "output": out.strip() or err.strip() or "Ingen filer gjenopprettet."}
    if zip_path and files:
        result["download"] = f"/api/download/{job}"
        result["files"] = files
    return result


def run_stegexpose(path):
    """StegExpose (Java). Statistisk LSB-deteksjon -> sannsynlighet for stego.

    Verktøyet jobber på en MAPPE, ikke enkeltfil, så vi kopierer fila inn i en
    dedikert temp-mappe og kjører mot den. Egner seg for PNG/BMP (tapsfri LSB).
    """
    if not STEGEXPOSE_JAR.exists():
        return {"tool": "stegexpose", "ok": False,
                "output": "StegExpose.jar mangler i tools/ — se README."}

    job = uuid.uuid4().hex
    d = UPLOAD_DIR / f"{job}_se"
    d.mkdir(exist_ok=True)
    shutil.copy(path, d / Path(path).name)

    rc, out, err = _run(["java", "-jar", str(STEGEXPOSE_JAR), str(d)])
    shutil.rmtree(d, ignore_errors=True)

    text = out.strip() or err.strip() or "Ingen resultat fra StegExpose."
    return {"tool": "stegexpose", "ok": rc == 0, "output": text}
