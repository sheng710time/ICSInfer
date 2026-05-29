from __future__ import annotations

import csv
from collections.abc import Mapping
from pathlib import Path


def get_vendor_name(row: Mapping[str, str]) -> str:
    """Prefer the canonical vendor label when it is available."""
    return (row.get("vendor_label") or row.get("vendor_norm") or row.get("vendor") or "").strip()


def build_device_label(row: Mapping[str, str]) -> str:
    """Build the canonical device label used across identification pipelines."""
    return "::".join(
        [
            get_vendor_name(row),
            (row.get("product_code") or "").strip(),
            (row.get("product_name") or "").strip(),
            (row.get("model_name") or "").strip(),
        ]
    )


def load_ip_labels(ip_label_file: str | Path) -> dict[str, str]:
    """Load IP-to-label mappings from a device information CSV file."""
    ip_labels: dict[str, str] = {}
    with open(ip_label_file, mode="r", newline="", encoding="utf-8-sig") as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            ip = (row.get("ip") or "").strip()
            if ip:
                ip_labels[ip] = build_device_label(row)
    return ip_labels
