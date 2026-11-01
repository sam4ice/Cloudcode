#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Iterable

SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
)


def normalize_target(target: str) -> str:
    cleaned = target.strip()
    if not cleaned:
        raise ValueError("Target cannot be empty.")
    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"
    parsed = urllib.parse.urlparse(cleaned)
    if not parsed.netloc:
        raise ValueError(f"Invalid target: {target}")
    return parsed.geturl()


def missing_security_headers(headers: dict[str, str]) -> list[str]:
    normalized = {key.lower() for key in headers}
    return [header for header in SECURITY_HEADERS if header.lower() not in normalized]


def scan_target(target: str, timeout: float = 5.0) -> dict[str, object]:
    normalized = normalize_target(target)
    request = urllib.request.Request(normalized, method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            headers = dict(response.headers.items())
            return {
                "target": normalized,
                "status": response.status,
                "server": headers.get("Server", "unknown"),
                "missing_headers": missing_security_headers(headers),
            }
    except urllib.error.HTTPError as error:
        headers = dict(error.headers.items()) if error.headers else {}
        return {
            "target": normalized,
            "status": error.code,
            "server": headers.get("Server", "unknown"),
            "missing_headers": missing_security_headers(headers),
            "error": error.reason,
        }
    except (urllib.error.URLError, TimeoutError) as error:
        return {
            "target": normalized,
            "status": None,
            "server": "unknown",
            "missing_headers": list(SECURITY_HEADERS),
            "error": str(error),
        }


def iter_targets(values: Iterable[str], file_path: str | None) -> list[str]:
    targets = list(values)
    if file_path:
        with open(file_path, "r", encoding="utf-8") as file:
            targets.extend(line.strip() for line in file if line.strip())
    return targets


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple bug bounty target scanner")
    parser.add_argument("targets", nargs="*", help="Target URLs or domains")
    parser.add_argument("--file", help="Path to file with one target per line")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()

    targets = iter_targets(args.targets, args.file)
    if not targets:
        parser.error("provide at least one target or --file")

    results = [scan_target(target, timeout=args.timeout) for target in targets]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for item in results:
            print(f"Target: {item['target']}")
            print(f"  Status: {item['status']}")
            print(f"  Server: {item['server']}")
            print(
                "  Missing headers: "
                + (", ".join(item["missing_headers"]) if item["missing_headers"] else "none")
            )
            if "error" in item:
                print(f"  Error: {item['error']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
