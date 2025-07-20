import os
import subprocess
import requests
import json
import zipfile
import tempfile
from pathlib import Path


#Hierbei handelt es sich um eine beispielhafte Implementierung. Der Quell-Code muss auf die Zielumgebung angepasst werden.

# === Konfiguration ===
EVENT_LOG_PATH = "C:\\Logs\\security.evtx" #Pfad zu extrahierten Security Event Logs auf xSoar Host
HAYABUSA_DIR = "C:\\Tools\\Hayabusa" #Pfad zu Hayabusa Installation
HAYABUSA_EXE = os.path.join(HAYABUSA_DIR, "hayabusa.exe") #Pfad zu Hayabusa Installation
HAYABUSA_OUTPUT = "C:\\Reports\\hayabusa_report.json"
NINA_API_URL = "http://open-webui.local/api/nina/evaluate" #Zum Ansprechen von dem Modell NiNa wird das Modell via der Rest API von Open Web UI angesprochen

HAYABUSA_RELEASE_URL = "https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-windows-x64.zip"

# === Schritt 0: Hayabusa herunterladen ===
def download_and_extract_hayabusa():
    if os.path.isfile(HAYABUSA_EXE):
        print("[*] Hayabusa ist bereits vorhanden.")
        return

    print("[*] Lade Hayabusa herunter...")
    os.makedirs(HAYABUSA_DIR, exist_ok=True)
    tmp_zip = os.path.join(tempfile.gettempdir(), "hayabusa.zip")

    response = requests.get(HAYABUSA_RELEASE_URL, stream=True)
    if response.status_code != 200:
        raise Exception("Fehler beim Herunterladen von Hayabusa.")

    with open(tmp_zip, 'wb') as f:
        for chunk in response.iter_content(1024):
            f.write(chunk)

    with zipfile.ZipFile(tmp_zip, 'r') as zip_ref:
        zip_ref.extractall(HAYABUSA_DIR)

    if not os.path.isfile(HAYABUSA_EXE):
        raise FileNotFoundError("Hayabusa.exe nicht gefunden nach dem Entpacken.")

    print(f"[+] Hayabusa installiert in: {HAYABUSA_EXE}")

# === Schritt 1: Eventlog prüfen ===
def validate_log_file(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Event Log nicht gefunden: {path}")
    print(f"[+] Event Log gefunden: {path}")

# === Schritt 2: Hayabusa Scan durchführen ===
def run_hayabusa(log_path, output_path):
    print("[*] Starte Hayabusa Scan...")
    cmd = [HAYABUSA_EXE, "scan", log_path, "--json", output_path]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[!] Fehler bei Hayabusa:\n{result.stderr}")
        raise RuntimeError("Hayabusa Analyse fehlgeschlagen.")
    print(f"[+] Hayabusa Bericht gespeichert unter: {output_path}")

# === Schritt 3: Bericht laden ===
def load_report(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)

# === Schritt 4: Bericht an NiNa senden ===
def evaluate_report(report):
    print("[*] Sende Bericht an NiNa...")
    headers = {"Content-Type": "application/json"}

    payload = {
        "input": json.dumps(report),
        "instruction": "Bewerte den Bericht nach Kritikalität und gib dazu eine fundierte Einschätzung ab."
    }

    response = requests.post(NINA_API_URL, headers=headers, json=payload)

    if response.status_code != 200:
        print(f"[!] API Fehler: {response.status_code}")
        raise RuntimeError(response.text)

    return response.json()

# === Hauptfunktion ===
def main():
    try:
        download_and_extract_hayabusa()
        validate_log_file(EVENT_LOG_PATH)
        os.makedirs(os.path.dirname(HAYABUSA_OUTPUT), exist_ok=True)
        run_hayabusa(EVENT_LOG_PATH, HAYABUSA_OUTPUT)
        report = load_report(HAYABUSA_OUTPUT)
        result = evaluate_report(report)

        print("\n[+] NiNa Bewertung:")
        print(result.get("output") or result)
    except Exception as e:
        print(f"[!] Fehler: {e}")

if __name__ == "__main__":
    main()
