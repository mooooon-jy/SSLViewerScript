from __future__ import annotations

import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import re
import subprocess
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "업무망_내부.md"
INDEX = ROOT / "index.html"
RESULTS = ROOT / "ssl-results.json"
HOST = os.environ.get("SSL_VIEWER_HOST", "0.0.0.0")
PORT = int(os.environ.get("SSL_VIEWER_PORT", "8084"))
RUNTIME_RESULTS = {}
RUNTIME_LOCK = threading.Lock()
AUTO_CHECK_STATUS = {"running": False, "completed": False, "checked": 0, "total": 0}
CHECK_TIMEOUT = int(os.environ.get("SSL_CHECK_TIMEOUT", "5"))
CHECK_WORKERS = int(os.environ.get("SSL_CHECK_WORKERS", "8"))


def load_targets() -> list[dict]:
    targets = []
    with SOURCE.open("r", encoding="utf-8-sig", newline="") as source:
        rows = csv.DictReader(source, delimiter="\t")
        for row_number, row in enumerate(rows, start=2):
            name = (row.get("이름") or "").strip()
            domain = (row.get("도메인") or "").strip()
            ports = re.findall(r"\d+", row.get("Port(SSL)") or "")
            if not name or not domain or not ports:
                continue
            hostname = f"{name}.{domain}".lower()
            for port in dict.fromkeys(ports):
                targets.append({
                    "id": f"{row_number}-{port}",
                    "name": name,
                    "service": (row.get("용도") or "").strip(),
                    "system": (row.get("시스템") or "").strip(),
                    "environment": (row.get("운영구분") or "").strip(),
                    "network": (row.get("내/외부") or "").strip(),
                    "hostname": hostname,
                    "port": int(port),
                    "address": f"{hostname}:{port}",
                    "sourceRow": row_number,
                    "note": (row.get("비고") or "").strip(),
                })
    return targets


def parse_certificate(raw: str) -> dict:
    dates = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"notBefore", "notAfter"}:
            dates[key] = value.strip()
    def format_date(value: str | None) -> str | None:
        if not value:
            return None
        try:
            parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
            return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            return value

    formatted_after = format_date(dates.get("notAfter"))
    result = {"notBefore": format_date(dates.get("notBefore")), "notAfter": formatted_after}
    if dates.get("notAfter"):
        try:
            expiry = datetime.strptime(result["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            result["daysRemaining"] = (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            try:
                expiry = datetime.strptime(result["notAfter"], "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
                result["daysRemaining"] = (expiry - datetime.now(timezone.utc)).days
            except ValueError:
                result["daysRemaining"] = None
    else:
        result["daysRemaining"] = None
    return result


def load_snapshot() -> dict:
    if not RESULTS.exists():
        return {"generatedAt": None, "results": {}}
    try:
        snapshot = json.loads(RESULTS.read_text(encoding="utf-8"))
        raw_results = snapshot.get("results", [])
        if isinstance(raw_results, dict):
            raw_results = [raw_results]
        while isinstance(raw_results, list) and raw_results and isinstance(raw_results[0], list):
            raw_results = [item for group in raw_results for item in group]
        results = {}
        for item in raw_results:
            if isinstance(item, dict) and item.get("id"):
                item.setdefault("source", "windows-powershell")
                results[item["id"]] = item
        return {"generatedAt": snapshot.get("generatedAt"), "results": results}
    except (OSError, json.JSONDecodeError, TypeError):
        return {"generatedAt": None, "results": {}}


def merge_snapshot_results(targets: list[dict], snapshot: dict) -> dict:
    results = dict(snapshot.get("results", {}))
    by_address = {
        f"{item.get('hostname', '').lower()}:{item.get('port')}": item
        for item in results.values()
        if item.get("hostname") and item.get("port")
    }
    for target in targets:
        if target["id"] not in results:
            result = by_address.get(target["address"].lower())
            if result:
                results[target["id"]] = result
    return results


def auto_check_targets() -> None:
    targets = load_targets()
    snapshot = load_snapshot()
    snapshot_results = merge_snapshot_results(targets, snapshot)
    pending = [target for target in targets if snapshot_results.get(target["id"], {}).get("source") != "windows-powershell"]
    AUTO_CHECK_STATUS.update({"running": True, "completed": False, "checked": 0, "total": len(pending)})
    def check_target(target: dict) -> tuple[str, dict]:
        try:
            result = check_certificate(target["hostname"], target["port"])
            result["source"] = "linux-openssl"
        except (RuntimeError, ValueError) as error:
            result = {"error": str(error), "source": "linux-openssl"}
        return target["id"], result

    with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as executor:
        futures = [executor.submit(check_target, target) for target in pending]
        for future in as_completed(futures):
            target_id, result = future.result()
            with RUNTIME_LOCK:
                RUNTIME_RESULTS[target_id] = result
            AUTO_CHECK_STATUS["checked"] += 1
    AUTO_CHECK_STATUS.update({"running": False, "completed": True})


def combined_results(targets: list[dict], snapshot: dict) -> dict:
    results = merge_snapshot_results(targets, snapshot)
    with RUNTIME_LOCK:
        results.update(RUNTIME_RESULTS)
    return results


def check_certificate(hostname: str, port: int) -> dict:
    if not re.fullmatch(r"[a-zA-Z0-9.-]+", hostname) or not 1 <= port <= 65535:
        raise ValueError("도메인 또는 포트 형식이 올바르지 않습니다.")

    command = [
        "openssl", "s_client", "-connect", f"{hostname}:{port}",
        "-servername", hostname,
    ]
    try:
        client = subprocess.run(
            command,
            input=b"\n",
            capture_output=True,
            timeout=CHECK_TIMEOUT,
            check=False,
        )
    except FileNotFoundError as error:
        raise RuntimeError("OpenSSL을 찾을 수 없습니다. PATH에 openssl을 추가해 주세요.") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("연결 시간이 초과되었습니다.") from error

    certificate_input = client.stdout
    if b"-----BEGIN CERTIFICATE-----" not in certificate_input:
        detail = (client.stderr or client.stdout).decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail or "TLS 인증서가 응답되지 않았습니다.")

    parsed = subprocess.run(
        ["openssl", "x509", "-noout", "-dates"],
        input=certificate_input,
        capture_output=True,
        timeout=CHECK_TIMEOUT,
        check=False,
    )
    if parsed.returncode != 0:
        detail = (parsed.stderr or client.stderr).decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail or "인증서를 확인할 수 없습니다.")

    return parse_certificate(parsed.stdout.decode("utf-8", errors="replace"))


class Handler(BaseHTTPRequestHandler):
    def send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/targets":
            targets = load_targets()
            snapshot = load_snapshot()
            snapshot["results"] = combined_results(targets, snapshot)
            self.send_json({"targets": targets, "snapshot": snapshot, "autoCheck": AUTO_CHECK_STATUS})
            return
        if path == "/" or path == "/index.html":
            body = INDEX.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/check":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            hostname = str(payload.get("hostname", "")).strip()
            port = int(payload.get("port", 0))
            certificate = check_certificate(hostname, port)
            self.send_json({"ok": True, "hostname": hostname, "port": port, **certificate})
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            self.send_json({"ok": False, "error": str(error)}, 400)
        except RuntimeError as error:
            self.send_json({"ok": False, "error": str(error)}, 502)

    def log_message(self, format: str, *args) -> None:
        return


if __name__ == "__main__":
    print("Starting one-time Linux certificate check...")
    auto_check_targets()
    try:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError as error:
        print(f"Cannot bind server to {HOST}:{PORT}: {error}")
        print("Use SSL_VIEWER_HOST=0.0.0.0 for all local interfaces, or an IP assigned to this server.")
        raise
    print(f"SSL certificate viewer: http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
