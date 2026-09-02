#!/usr/bin/env python3
"""Compare live Dumont Secrets pin vs Bitwarden browser + OIDCWarden tags.

Notify Hangar (SEC) and Dumont Chat (#alerts-dumont-secrets) only when a
version actually changes — not every daily run of the same lag.

Usage:
  python3 compat-watch.py --check-only
  python3 compat-watch.py --notify
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

PIN_PATH = Path(__file__).resolve().parent / "PIN.json"
DEFAULT_STATE = Path(os.environ.get("COMPAT_WATCH_STATE", "/var/lib/dumont-secrets-watch/state.json"))
HANGAR_PROJECT = "ac913f1a-fa7f-4c98-848b-b0ae826f7117"
UA = "DumontSecretsCompatWatch/1.0 (+https://secret.getdumont.ai)"


def parse_ver(text: str) -> tuple[int, int, int] | None:
    match = re.search(r"(\d{4})\.(\d+)\.(\d+)", text or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def ver_str(version: tuple[int, int, int] | None) -> str:
    if version is None:
        return "unknown"
    return f"{version[0]}.{version[1]}.{version[2]}"


def newer(left: tuple[int, int, int] | None, right: tuple[int, int, int] | None) -> bool:
    if left is None or right is None:
        return False
    return left > right


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def load_env_file(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.exists():
        return data
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip("\"'")
    return data


def http_json(url: str, headers: dict[str, str] | None = None) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=25) as response:
        return json.loads(response.read().decode())


def http_json_method(method: str, url: str, headers: dict[str, str], payload: dict[str, Any] | None = None) -> tuple[int, Any]:
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, headers={**headers, "User-Agent": UA}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            raw = response.read().decode()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"raw": raw[:400]}
        return exc.code, parsed


def fetch_live(vault_url: str) -> dict[str, Any]:
    config = http_json(vault_url.rstrip("/") + "/api/config")
    return {
        "version": config.get("version"),
        "git_hash": (config.get("gitHash") or "")[:12],
        "sso": bool((config.get("settings") or {}).get("ssoEnabled")),
    }


def fetch_oidcwarden_latest() -> str:
    tags = http_json("https://api.github.com/repos/Timshel/OIDCWarden/tags?per_page=20")
    for item in tags:
        name = item.get("name") or ""
        if parse_ver(name):
            return name
    return ""


def fetch_browser_latest() -> str:
    releases = http_json("https://api.github.com/repos/bitwarden/clients/releases?per_page=30")
    for item in releases:
        tag = item.get("tag_name") or ""
        if tag.startswith("browser-v"):
            return tag
    return ""


def collect(pin: dict[str, Any]) -> dict[str, Any]:
    live = fetch_live(pin.get("vault_url") or "https://secret.getdumont.ai")
    oidc = fetch_oidcwarden_latest()
    browser = fetch_browser_latest()
    pin_ver = parse_ver(pin.get("upstream_tag") or pin.get("dumont_tag") or "")
    min_browser = parse_ver(pin.get("min_browser") or "")
    oidc_ver = parse_ver(oidc)
    browser_ver = parse_ver(browser)
    live_ver = parse_ver(live.get("version") or "")
    reasons: list[str] = []
    if newer(oidc_ver, pin_ver):
        reasons.append(f"OIDCWarden {oidc} à frente do pin {pin.get('upstream_tag')}")
    if newer(browser_ver, min_browser):
        reasons.append(f"Extensão Bitwarden {browser} à frente do mínimo coberto {pin.get('min_browser')}")
    live_sha = (live.get("git_hash") or "")[:8]
    pin_sha = (pin.get("upstream_sha") or "")[:8]
    if live_sha and pin_sha and live_sha != pin_sha:
        reasons.append(f"Live gitHash {live_sha} diverge do pin {pin_sha}")
    return {
        "pin_tag": pin.get("dumont_tag"),
        "pin_upstream": pin.get("upstream_tag"),
        "pin_sha": pin_sha,
        "min_browser": pin.get("min_browser"),
        "live_version": live.get("version"),
        "live_sha": live_sha,
        "oidc_latest": oidc,
        "browser_latest": browser,
        "browser_ver": ver_str(browser_ver),
        "oidc_ver": ver_str(oidc_ver),
        "drift": bool(reasons),
        "reasons": reasons,
    }


def snapshot(report: dict[str, Any]) -> dict[str, str]:
    return {
        "browser_latest": report["browser_latest"],
        "oidc_latest": report["oidc_latest"],
        "live_sha": report["live_sha"],
        "pin_tag": report["pin_tag"],
    }


def format_message(report: dict[str, Any]) -> str:
    if report["drift"]:
        return "\n".join(
            [
                "Oi, time —",
                "",
                "A extensão Bitwarden do Chrome atualizou sozinha. O cofre Dumont Secrets ainda não.",
                "",
                "Por isso a extensão pode falhar: logout sozinho, cofre vazio ou “unexpected error”.",
                "",
                "**O que fazer agora (2 minutos)**",
                "1. Clique no ícone da extensão Bitwarden.",
                "2. Faça **Log out** (sair da conta). Não basta só bloquear / cadeado.",
                "3. Em Server, escolha **Self-hosted** e cole: `https://secret.getdumont.ai`",
                "4. Entre com **Use SSO** (login Dumont) e destrave.",
                "",
                "Se o cofre vier vazio depois disso: desinstale a extensão, instale de novo, e repita os 4 passos.",
                "",
                "**O que NÃO precisa fazer**",
                "- Não precisa baixar a extensão na mão. O Chrome já atualiza.",
                "- Não mexa no servidor. O bump do cofre é janela controlada; avisamos neste canal quando subir.",
                "",
                "Quando o canal disser “cofre atualizado”: o mesmo logout + SSO de novo.",
                "",
                f"Agora: extensão `{report['browser_latest']}` · cofre pin `{report['pin_tag']}` · OIDCWarden disponível `{report['oidc_latest']}`",
                "Cofre: https://secret.getdumont.ai",
            ]
        )
    return "\n".join(
        [
            "Oi, time —",
            "",
            "Relógio do Dumont Secrets: pin e extensão estão alinhados. Nada para vocês fazerem.",
            "",
            f"Extensão `{report['browser_latest']}` · pin `{report['pin_tag']}` · live `{report['live_sha']}`",
            "Cofre: https://secret.getdumont.ai",
        ]
    )


def notify_chat(text: str) -> None:
    secrets = load_env_file(Path("/opt/secrets/.env"))
    webhook = secrets.get("MM_SECRETS_WEBHOOK") or os.environ.get("MM_SECRETS_WEBHOOK")
    if not webhook:
        raise SystemExit("MM_SECRETS_WEBHOOK missing")
    payload = json.dumps(
        {
            "text": text,
            "username": "Dumont Secrets",
        }
    ).encode()
    req = urllib.request.Request(
        webhook,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": UA},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        response.read()


def notify_hangar(report: dict[str, Any], text: str) -> str | None:
    secrets = load_env_file(Path("/opt/secrets/.env"))
    token = secrets.get("HANGAR_API_TOKEN") or os.environ.get("HANGAR_API_TOKEN")
    base = (secrets.get("HANGAR_API_URL") or os.environ.get("HANGAR_API_URL") or "http://127.0.0.1:3070").rstrip("/")
    if not token:
        raise SystemExit("HANGAR_API_TOKEN missing")
    title = (
        f"Extensão {report['browser_ver']} vs pin {report['pin_upstream']}"
        if report["drift"]
        else f"Pin alinhado — {report['pin_tag']}"
    )
    html = "<br/>".join(text.splitlines())
    headers = {"X-API-Key": token, "Content-Type": "application/json"}
    payloads = [
        {"name": title, "description_html": f"<p>{html}</p>"},
        {"name": title, "description": text},
    ]
    for payload in payloads:
        code, created = http_json_method(
            "POST",
            f"{base}/api/v1/workspaces/dumont/projects/{HANGAR_PROJECT}/issues/",
            headers,
            payload,
        )
        if code in {200, 201} and isinstance(created, dict) and created.get("id"):
            seq = created.get("sequence_id") or created.get("id")
            return f"https://hangar.getdumont.ai/dumont/browse/SEC-{seq}" if str(seq).isdigit() else str(seq)
    print("hangar_create_failed", file=sys.stderr)
    return None


def print_report(report: dict[str, Any]) -> None:
    print(json.dumps({k: report[k] for k in report if k != "reasons"} | {"reasons": report["reasons"]}, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--notify", action="store_true")
    parser.add_argument("--force", action="store_true", help="notify even if snapshot unchanged")
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    args = parser.parse_args()
    pin = load_json(PIN_PATH)
    report = collect(pin)
    print_report(report)
    if args.check_only:
        return 1 if report["drift"] else 0
    if not args.notify:
        return 1 if report["drift"] else 0

    current = snapshot(report)
    args.state.parent.mkdir(parents=True, exist_ok=True)
    previous = load_json(args.state) if args.state.exists() else {}
    if current == previous and not args.force:
        print("unchanged — no notify")
        return 1 if report["drift"] else 0

    text = format_message(report)
    hangar_url = notify_hangar(report, text)
    if hangar_url:
        text += f"\nCard: {hangar_url}"
    notify_chat(text)
    args.state.write_text(json.dumps(current, indent=2) + "\n")
    print("notified")
    return 1 if report["drift"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
