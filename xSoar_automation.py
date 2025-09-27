from CommonServerPython import *  
import os, re, io, zipfile, tempfile, shutil, subprocess, requests, json

# Args:
#   entry_id: War Room Datei-Entry-ID einer .evtx Datei (oder .zip mit evtx-Dateien)
#   nina_url: (optional) überschreibt NiNa API URL; ansonsten Parameter
# Params:
#   nina_url: Standard NiNa API URL (z. B. http://open-webui.local/api/nina/evaluate)
#   hayabusa_release_url: optionaler Override; Standard ist Linux x64 Build
#   verify_ssl: (bool) SSL-Validierung für HTTP-Requests (z. B. interne NiNa-URL mit Self-Signed)
#   request_timeout: (int) Timeout in Sekunden für HTTP-Requests (Default 120 Download / 300 Post)

DEFAULT_HAYABUSA_URL = 'https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-linux-x64.zip'
DEFAULT_DL_TIMEOUT = 120
DEFAULT_POST_TIMEOUT = 300


def _safe_extract_evtx(zf: zipfile.ZipFile, target_dir: str) -> int:
    """
    Extrahiert ausschließlich .evtx Dateien sicher nach target_dir (Zip-Slip Schutz).
    Gibt die Anzahl extrahierter Dateien zurück.
    """
    extracted = 0
    for member in zf.infolist():
        # Nur .evtx Dateien
        if not member.filename.lower().endswith('.evtx'):
            continue
        # Normiere Pfad & verhindere Zip-Slip
        # (kein Eintrag darf ausserhalb von target_dir landen)
        member_path = os.path.normpath(member.filename)
        # Verhindere absolute Pfade oder Laufwerksangaben
        if member_path.startswith(('/', '\\')) or re.match(r'^[a-zA-Z]:', member_path):
            continue
        dest_path = os.path.join(target_dir, member_path)
        dest_path = os.path.normpath(dest_path)
        if not dest_path.startswith(os.path.abspath(target_dir) + os.sep):
            continue
        # Zielordner anlegen und extrahieren
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with zf.open(member) as src, open(dest_path, 'wb') as dst:
            shutil.copyfileobj(src, dst)
        extracted += 1
    return extracted


def download_and_extract_hayabusa(hayabusa_zip_url: str, workdir: str, verify_ssl: bool, timeout: int) -> str:
    bin_dir = os.path.join(workdir, 'hayabusa')
    os.makedirs(bin_dir, exist_ok=True)
    zip_path = os.path.join(workdir, 'hayabusa.zip')

    res = requests.get(hayabusa_zip_url, stream=True, timeout=timeout, verify=verify_ssl)
    if res.status_code != 200:
        raise DemistoException(f'Fehler beim Herunterladen von Hayabusa (HTTP {res.status_code})')
    with open(zip_path, 'wb') as f:
        for chunk in res.iter_content(128 * 1024):
            if chunk:
                f.write(chunk)

    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(bin_dir)

    # Suche nach dem ausführbaren Binary
    cand = None
    for root, _, files in os.walk(bin_dir):
        for fn in files:
            if (fn == 'hayabusa') or (fn.startswith('hayabusa') and not fn.endswith('.zip')):
                cand = os.path.join(root, fn)
                break
        if cand:
            break
    if not cand:
        raise DemistoException('hayabusa Binary nach dem Entpacken nicht gefunden')

    os.chmod(cand, 0o755)
    return cand


def ensure_input_files(entry_id: str, workdir: str) -> str:
    """Stellt sicher, dass mindestens eine .evtx Datei vorliegt (liefert Verzeichnis zurück)."""
    file_info = demisto.getFilePath(entry_id)
    src_path = file_info.get('path')
    if not src_path or not os.path.exists(src_path):
        raise DemistoException(f'Konnte Entry-ID {entry_id} nicht lesen')

    target_dir = os.path.join(workdir, 'input')
    os.makedirs(target_dir, exist_ok=True)

    # Falls ZIP: sicher entpacken, sonst Einzeldatei kopieren
    if zipfile.is_zipfile(src_path):
        with zipfile.ZipFile(src_path, 'r') as z:
            count = _safe_extract_evtx(z, target_dir)
            if count == 0:
                # Fallback: Falls ZIP keine .evtx direkt enthielt, entpacke trotzdem (mit Zip-Slip Schutz)
                for member in z.infolist():
                    member_path = os.path.normpath(member.filename)
                    if member_path.startswith(('/', '\\')) or re.match(r'^[a-zA-Z]:', member_path):
                        continue
                    dest_path = os.path.join(target_dir, member_path)
                    dest_path = os.path.normpath(dest_path)
                    if not dest_path.startswith(os.path.abspath(target_dir) + os.sep):
                        continue
                    # Nur Dateien extrahieren
                    if not member.is_dir():
                        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                        with z.open(member) as src, open(dest_path, 'wb') as dst:
                            shutil.copyfileobj(src, dst)
    else:
        shutil.copy2(src_path, os.path.join(target_dir, os.path.basename(src_path)))

    # Prüfen ob .evtx Dateien vorhanden
    evtx_found = False
    for root, _, files in os.walk(target_dir):
        if any(f.lower().endswith('.evtx') for f in files):
            evtx_found = True
            break
    if not evtx_found:
        raise DemistoException('Keine .evtx Dateien gefunden')
    return target_dir


def run_hayabusa(hayabusa_bin: str, input_dir: str, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    csv_path = os.path.join(out_dir, 'timeline.csv')
    html_path = os.path.join(out_dir, 'report.html')

    args = [
        hayabusa_bin, 'csv-timeline',
        '-d', input_dir,
        '-o', csv_path,   # CSV Zieldatei
        '-H', html_path   # HTML Report Zieldatei
    ]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise DemistoException(f'Fehler bei Hayabusa.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}')

    if not os.path.isfile(html_path):
        raise DemistoException('report.html nach Lauf nicht gefunden')
    return html_path


def html_to_text(html: str, max_len: int = 500_000) -> str:
    # Minimaler HTML→Text Fallback (kein BeautifulSoup)
    txt = re.sub(r'(?is)<(script|style|noscript).*?</\1>', '', html)
    txt = re.sub(r'(?s)<[^>]+>', '\n', txt)
    txt = re.sub(r'\n{2,}', '\n', txt).strip()
    if len(txt) > max_len:
        txt = txt[:max_len] + '\n...[gekürzt]'
    return txt


def post_to_nina(url: str, text: str, verify_ssl: bool, timeout: int) -> dict:
    payload = {
        'input': text,
        'instruction': 'Bewerte den Bericht nach Kritikalität und gib dazu eine fundierte Einschätzung ab.'
    }
    headers = {'Content-Type': 'application/json'}
    res = requests.post(url, json=payload, headers=headers, timeout=timeout, verify=verify_ssl)
    if res.status_code != 200:
        raise DemistoException(f'NiNa API Fehler {res.status_code}: {res.text}')
    # Bestehende APIs liefern teils {output: "..."} oder direkt Text
    try:
        return res.json()
    except Exception:
        return {'output': res.text}


def main():
    # Proxy-Einstellungen aus XSOAR berücksichtigen
    try:
        handle_proxy()  # setzt env vars, wenn im Instance-Config aktiviert
    except Exception:
        pass

    workdir = tempfile.mkdtemp(prefix='hayabusa_xsoar_')
    try:
        args = demisto.args()
        params = demisto.params() or {}

        entry_id = args.get('entry_id')
        if not entry_id:
            raise DemistoException('Bitte entry_id einer hochgeladenen .evtx (oder .zip) angeben.')

        nina_url = args.get('nina_url') or params.get('nina_url')
        if not nina_url:
            raise DemistoException('Keine NiNa URL konfiguriert (Parameter oder Argument nina_url).')

        hayabusa_url = params.get('hayabusa_release_url') or DEFAULT_HAYABUSA_URL
        verify_ssl = bool(params.get('verify_ssl', True))
        dl_timeout = int(params.get('request_timeout', DEFAULT_DL_TIMEOUT))
        post_timeout = int(params.get('post_timeout', DEFAULT_POST_TIMEOUT))
        max_text_len = int(params.get('max_text_len', 500_000))

        demisto.debug(f'Lade Hayabusa von {hayabusa_url} herunter')
        hayabusa_bin = download_and_extract_hayabusa(hayabusa_url, workdir, verify_ssl, dl_timeout)

        demisto.debug('Bereite Eingabedateien vor')
        input_dir = ensure_input_files(entry_id, workdir)

        demisto.debug('Starte Hayabusa Analyse')
        out_dir = os.path.join(workdir, 'out')
        report_path = run_hayabusa(hayabusa_bin, input_dir, out_dir)

        with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
            html = f.read()
        text = html_to_text(html, max_len=max_text_len)

        demisto.debug('Sende Auswertung an NiNa')
        nina_result = post_to_nina(nina_url, text, verify_ssl, post_timeout)
        nina_output = nina_result.get('output') or json.dumps(nina_result, ensure_ascii=False, indent=2)

        # Report ins War Room hochladen
        with open(report_path, 'rb') as f:
            report_bytes = f.read()
        upload = fileResult('hayabusa_report.html', report_bytes, file_type=EntryType.ENTRY_INFO_FILE)

        md = f'### NiNa Bewertung\n\n{nina_output}'
        results = [
            CommandResults(
                readable_output=md,
                outputs_prefix='Hayabusa.NiNa',
                outputs={'Bewertung': nina_output}
            ),
            upload
        ]
        return_results(results)

    except Exception as e:
        return_error(f'HayabusaXSOAR: {str(e)}')
    finally:
        try:
            shutil.rmtree(workdir, ignore_errors=True)
        except Exception:
            pass


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
