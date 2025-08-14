import os
import subprocess
import requests
import json
import zipfile
import tempfile
import re
from pathlib import Path

# Hierbei handelt es sich um eine beispielhafte Implementierung. Der Quell-Code muss auf die Zielumgebung angepasst werden.

# === Konfiguration ===
# Pfad zu extrahierten Security Event Logs (Datei ODER Verzeichnis)
EVENT_LOG_PATH = r"C:\Logs\security.evtx"

# Pfad zur Hayabusa-Installation
HAYABUSA_DIR = r"C:\Tools\Hayabusa"
HAYABUSA_EXE = os.path.join(HAYABUSA_DIR, "hayabusa.exe")

# Zielordner für Reporte
HAYABUSA_REPORT_DIR = r"C:\Reports\Hayabusa"
REPORT_HTML_NAME = "report.html"

# NiNa API Endpoint (Open WebUI)
NINA_API_URL = "http://open-webui.local/api/nina/evaluate"

# Release (Windows x64)
HAYABUSA_RELEASE_URL = "https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-windows-x64.zip"


# === Schritt 0: Hayabusa herunterladen/entpacken (falls nötig) ===
def download_and_extract_hayabusa():
    if os.path.isfile(HAYABUSA_EXE):
        print("[*] Hayabusa ist bereits vorhanden.")
        return

    print("[*] Lade Hayabusa herunter...")
    os.makedirs(HAYABUSA_DIR, exist_ok=True)
    tmp_zip = os.path.join(tempfile.gettempdir(), "hayabusa.zip")

    response = requests.get(HAYABUSA_RELEASE_URL, stream=True, timeout=120)
    if response.status_code != 200:
        raise Exception(f"Fehler beim Herunterladen von Hayabusa (HTTP {response.status_code}).")

    with open(tmp_zip, 'wb') as f:
        for chunk in response.iter_content(1024 * 128):
            if chunk:
                f.write(chunk)

    with zipfile.ZipFile(tmp_zip, 'r') as zip_ref:
        zip_ref.extractall(HAYABUSA_DIR)

    if not os.path.isfile(HAYABUSA_EXE):
        # Manche Releases entpacken in Unterordner – wir suchen die exe
        for root, _, files in os.walk(HAYABUSA_DIR):
            if "hayabusa.exe" in files:
                exe_path = os.path.join(root, "hayabusa.exe")
                # ggf. ins Ziel kopieren
                if exe_path != HAYABUSA_EXE:
                    Path(HAYABUSA_EXE).write_bytes(Path(exe_path).read_bytes())
                break

    if not os.path.isfile(HAYABUSA_EXE):
        raise FileNotFoundError("hayabusa.exe nicht gefunden nach dem Entpacken.")

    print(f"[+] Hayabusa installiert in: {HAYABUSA_EXE}")


# === Schritt 1: Eventlog prüfen ===
def validate_input_path(path: str):
    if not (os.path.isfile(path) or os.path.isdir(path)):
        raise FileNotFoundError(f"Event Log Pfad nicht gefunden (Datei oder Ordner erwartet): {path}")
    print(f"[+] Eingabepfad gefunden: {path}")


# === Schritt 2: Hayabusa Scan durchführen (HTML-Export) ===
def run_hayabusa(input_path: str, output_dir: str) -> str:
    """
    Führt Hayabusa mit csv-timeline aus.
    - Wenn input_path ein Ordner ist -> -d <dir>
    - Wenn input_path eine Datei ist -> -f <file>
    Exportiert HTML nach <output_dir>/report.html
    """
    os.makedirs(output_dir, exist_ok=True)
    is_dir = os.path.isdir(input_path)

    if not os.path.isfile(HAYABUSA_EXE):
        raise FileNotFoundError(f"hayabusa.exe nicht gefunden: {HAYABUSA_EXE}")

    args = [
        HAYABUSA_EXE,
        "csv-timeline",
        "-H", REPORT_HTML_NAME,
        "-o", output_dir,
    ]
    if is_dir:
        args += ["-d", input_path]
    else:
        args += ["-f", input_path]

    print("[*] Starte Hayabusa Scan...")
    # Auf Windows: shell=False, direkt exe aufrufen
    result = subprocess.run(args, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[!] Fehler bei Hayabusa:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
        raise RuntimeError("Hayabusa Analyse fehlgeschlagen.")

    report_html = os.path.join(output_dir, REPORT_HTML_NAME)
    if not os.path.isfile(report_html):
        # Manche Versionen könnten in Unterordner schreiben – wir suchen den Report sicherheitshalber
        candidate = None
        for root, _, files in os.walk(output_dir):
            if REPORT_HTML_NAME in files:
                candidate = os.path.join(root, REPORT_HTML_NAME)
                break
        if candidate:
            report_html = candidate
        else:
            raise FileNotFoundError(f"HTML Report nicht gefunden in {output_dir}")

    print(f"[+] Hayabusa Bericht gespeichert unter: {report_html}")
    return report_html


# === Schritt 3: HTML Bericht laden und in Text/JSON-ähnliche Struktur transformieren ===
def load_report_as_text(html_path: str) -> str:
    """
    Liest report.html und extrahiert lesbaren Text für die Bewertung.
    Nutzt BeautifulSoup, wenn vorhanden; ansonsten Fallback mit Regex.
    """
    with open(html_path, "r", encoding="utf-8", errors="ignore") as f:
        html = f.read()

    try:
        from bs4 import BeautifulSoup  # optional dependency
        soup = BeautifulSoup(html, "html.parser")

        # Entferne Skripte/Styles
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()

        text = soup.get_text(separator="\n", strip=True)

        # Optional: auf sinnvolle Länge kürzen (z. B. 500k Zeichen), um API-Limits zu schonen
        max_len = 500_000
        if len(text) > max_len:
            text = text[:max_len] + "\n...[gekürzt]"

        return text

    except Exception:
        # Fallback: Primitive Tag-Entfernung
        text = re.sub(r"(?is)<(script|style).*?</\1>", "", html)
        text = re.sub(r"(?s)<[^>]+>", "\n", text)
        text = re.sub(r"\n{2,}", "\n", text)
        text = text.strip()

        max_len = 500_000
        if len(text) > max_len:
            text = text[:max_len] + "\n...[gekürzt]"

        return text


# === Schritt 4: Bericht an NiNa senden ===
def evaluate_report(report_text: str):
    """
    Sendet den (aus HTML extrahierten) Text an NiNa.
    """
    print("[*] Sende Bericht an NiNa...")
    headers = {"Content-Type": "application/json"}

    payload = {
        "input": report_text,
        "instruction": (
            "Bewerte den Bericht nach Kritikalität und gib dazu eine fundierte Einschätzung ab."
        ),
    }

    response = requests.post(NINA_API_URL, headers=headers, json=payload, timeout=300)

    if response.status_code != 200:
        print(f"[!] API Fehler: {response.status_code}")
        raise RuntimeError(response.text)

    return response.json()


# === Hauptfunktion ===
def main():
    try:
        download_and_extract_hayabusa()
        validate_input_path(EVENT_LOG_PATH)

        os.makedirs(HAYABUSA_REPORT_DIR, exist_ok=True)

        report_html_path = run_hayabusa(EVENT_LOG_PATH, HAYABUSA_REPORT_DIR)
        report_text = load_report_as_text(report_html_path)
        result = evaluate_report(report_text)

        print("\n[+] NiNa Bewertung:")
        print(result.get("output") or result)

    except Exception as e:
        print(f"[!] Fehler: {e}")


if __name__ == "__main__":
    main()
