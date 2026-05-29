"""
Dataset IP anonymization for ICSInfer.

The anonymizer keeps IP addresses consistent within each data source while using
different Crypto-PAn seeds across sources. This prevents accidental linkage
between the ICS, honeypot, and Shodan collections.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


BASE_CRYPTOPAN_KEY_SEED = "01234567_AaBbCcD01234567_AaBbCcD"
SOURCE_KEY_SEEDS: Mapping[str, str] = {
    "ics": f"{BASE_CRYPTOPAN_KEY_SEED}_ics",
    "honeypot": f"{BASE_CRYPTOPAN_KEY_SEED}_honeypot",
    "shodan": f"{BASE_CRYPTOPAN_KEY_SEED}_shodan",
}
DEFAULT_DATASET_ROOT = Path("dataset")
DEFAULT_OUTPUT_DATASET_ROOT = Path("anonymized_dataset")
DEFAULT_DROP_REGION_TOKENS = ("au",)
IP_FILENAME_PATTERN = re.compile(r"(?<!\d)(\d{1,3}(?:\.\d{1,3}){3})(?!\d)")


def derive_cryptopan_key(seed: str) -> bytes:
    """Derive the fixed 32-byte Crypto-PAn key required by the algorithm."""
    return hashlib.sha256(seed.encode("utf-8")).digest()


class CryptoPAnIPv4:
    """Prefix-preserving IPv4 anonymizer compatible with the Crypto-PAn design."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Crypto-PAn requires a 32-byte key.")
        self._aes_key = key[:16]
        self._pad = int.from_bytes(key[16:], byteorder="big")
        self._cipher = Cipher(algorithms.AES(self._aes_key), modes.ECB())

    def _encrypt_msb(self, block: int) -> int:
        encryptor = self._cipher.encryptor()
        encrypted = encryptor.update(block.to_bytes(16, byteorder="big")) + encryptor.finalize()
        return encrypted[0] >> 7

    def anonymize(self, ip_value: str) -> str:
        address = int(ipaddress.IPv4Address(ip_value))
        anonymized = 0

        for bit_index in range(32):
            prefix_len = bit_index
            if prefix_len == 0:
                block = self._pad
            else:
                prefix = address >> (32 - prefix_len)
                block = (prefix << (128 - prefix_len)) | (self._pad & ((1 << (128 - prefix_len)) - 1))

            original_bit = (address >> (31 - bit_index)) & 1
            anonymized_bit = original_bit ^ self._encrypt_msb(block)
            anonymized = (anonymized << 1) | anonymized_bit

        return str(ipaddress.IPv4Address(anonymized))


class IPAnonymizer:
    """Prefix-preserving IPv4 anonymizer with an in-memory cache."""

    def __init__(self, key_seed: str):
        self.key_seed = key_seed
        self._cryptopan = CryptoPAnIPv4(derive_cryptopan_key(key_seed))
        self._cache: Dict[str, str] = {}

    def anonymize(self, ip_value: str) -> str:
        text = (ip_value or "").strip()
        if not text:
            return text
        if text not in self._cache:
            try:
                ipaddress.IPv4Address(text)
            except ValueError:
                return text
            self._cache[text] = self._cryptopan.anonymize(text)
        return self._cache[text]

    def mapping_items(self) -> List[Sequence[str]]:
        return sorted(self._cache.items())


def detect_sources(dataset_root: Path) -> List[str]:
    return sorted(source for source in SOURCE_KEY_SEEDS if (dataset_root / source).is_dir())


def anonymize_filename(
    filename: str,
    anonymizer: IPAnonymizer,
    drop_region_tokens: Iterable[str],
) -> str:
    def replace_ip(match: re.Match[str]) -> str:
        return anonymizer.anonymize(match.group(1))

    anonymized = IP_FILENAME_PATTERN.sub(replace_ip, filename)
    for token in drop_region_tokens:
        anonymized = anonymized.replace(f"_{token}_", "_").replace(f"_{token}.", ".")
    return anonymized


def anonymize_csv_file(input_path: Path, output_path: Path, anonymizer: IPAnonymizer) -> Dict[str, object]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    row_count = 0
    anonymized_ip_count = 0

    with input_path.open("r", newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None:
            raise ValueError(f"CSV file has no header: {input_path}")

        rows = []
        for row in reader:
            row_count += 1
            original_ip = row.get("ip", "")
            anonymized_ip = anonymizer.anonymize(original_ip)
            if anonymized_ip != original_ip:
                anonymized_ip_count += 1
                row["ip"] = anonymized_ip
            rows.append(row)

    with output_path.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=reader.fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    return {
        "input": str(input_path),
        "output": str(output_path),
        "row_count": row_count,
        "anonymized_ip_count": anonymized_ip_count,
    }


def anonymize_pcap_file(input_path: Path, output_path: Path, anonymizer: IPAnonymizer) -> Dict[str, object]:
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.utils import PcapReader, PcapWriter

    def reset_ip_related_checksums(packet) -> None:
        if IP not in packet:
            return
        if hasattr(packet[IP], "len"):
            del packet[IP].len
        if hasattr(packet[IP], "chksum"):
            del packet[IP].chksum
        if TCP in packet and hasattr(packet[TCP], "chksum"):
            del packet[TCP].chksum
        if UDP in packet:
            if hasattr(packet[UDP], "len"):
                del packet[UDP].len
            if hasattr(packet[UDP], "chksum"):
                del packet[UDP].chksum
        if ICMP in packet and hasattr(packet[ICMP], "chksum"):
            del packet[ICMP].chksum

    output_path.parent.mkdir(parents=True, exist_ok=True)
    packet_count = 0
    ip_packet_count = 0
    rewritten_endpoint_count = 0

    with PcapReader(str(input_path)) as reader, PcapWriter(str(output_path), append=False, sync=False) as writer:
        for packet in reader:
            packet_count += 1
            changed = False
            if IP in packet:
                ip_packet_count += 1
                original_src = packet[IP].src
                original_dst = packet[IP].dst
                new_src = anonymizer.anonymize(original_src)
                new_dst = anonymizer.anonymize(original_dst)

                if new_src != original_src:
                    packet[IP].src = new_src
                    rewritten_endpoint_count += 1
                    changed = True
                if new_dst != original_dst:
                    packet[IP].dst = new_dst
                    rewritten_endpoint_count += 1
                    changed = True
                if changed:
                    reset_ip_related_checksums(packet)

            writer.write(packet)

    return {
        "input": str(input_path),
        "output": str(output_path),
        "packet_count": packet_count,
        "ip_packet_count": ip_packet_count,
        "rewritten_endpoint_count": rewritten_endpoint_count,
    }


def anonymize_source(
    dataset_root: Path,
    output_root: Path,
    source: str,
    skip_csv: bool,
    skip_pcap: bool,
    drop_region_tokens: Sequence[str],
) -> Dict[str, object]:
    input_source_root = dataset_root / source
    output_source_root = output_root / source
    anonymizer = IPAnonymizer(SOURCE_KEY_SEEDS[source])

    summary: Dict[str, object] = {
        "source": source,
        "csv_files": [],
        "pcap_files": [],
    }

    if not skip_csv:
        for csv_path in sorted(input_source_root.glob("*.csv")):
            output_path = output_source_root / csv_path.name
            summary["csv_files"].append(anonymize_csv_file(csv_path, output_path, anonymizer))

    if not skip_pcap:
        for pcap_path in sorted(input_source_root.rglob("*.pcap")):
            relative_path = pcap_path.relative_to(input_source_root)
            output_name = anonymize_filename(relative_path.name, anonymizer, drop_region_tokens)
            output_path = output_source_root / relative_path.parent / output_name
            summary["pcap_files"].append(anonymize_pcap_file(pcap_path, output_path, anonymizer))

    mapping_rows = anonymizer.mapping_items()
    summary["distinct_ip_count"] = len(mapping_rows)
    return summary | {"mapping_rows": mapping_rows}


def write_mapping_csv(output_root: Path, source: str, mapping_rows: Sequence[Sequence[str]]) -> Path:
    output_dir = output_root / "anonymization"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{source}_ip_mapping.csv"
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["source", "original_ip", "anonymized_ip"])
        for original_ip, anonymized_ip in mapping_rows:
            writer.writerow([source, original_ip, anonymized_ip])
    return output_path


def write_summary_json(output_root: Path, summary: Mapping[str, object]) -> Path:
    output_dir = output_root / "anonymization"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "anonymization_summary.json"
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, ensure_ascii=False)
    return output_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Anonymize IP addresses in the ICSInfer dataset.")
    parser.add_argument("--dataset-root", default=str(DEFAULT_DATASET_ROOT))
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_DATASET_ROOT))
    parser.add_argument("--sources", nargs="+", choices=sorted(SOURCE_KEY_SEEDS), default=None)
    parser.add_argument("--skip-csv", action="store_true")
    parser.add_argument("--skip-pcap", action="store_true")
    parser.add_argument("--write-mapping", action="store_true")
    parser.add_argument(
        "--drop-region-token",
        action="append",
        default=list(DEFAULT_DROP_REGION_TOKENS),
        help="Region token to remove from output pcap filenames, e.g. au.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    dataset_root = Path(args.dataset_root)
    output_root = Path(args.output_root)
    sources = args.sources or detect_sources(dataset_root)

    summary: Dict[str, object] = {
        "dataset_root": str(dataset_root),
        "output_root": str(output_root),
        "sources": [],
    }

    for source in sources:
        source_summary = anonymize_source(
            dataset_root=dataset_root,
            output_root=output_root,
            source=source,
            skip_csv=args.skip_csv,
            skip_pcap=args.skip_pcap,
            drop_region_tokens=args.drop_region_token,
        )
        mapping_rows = source_summary.pop("mapping_rows")
        if args.write_mapping:
            mapping_csv_path = write_mapping_csv(output_root, source, mapping_rows)
            source_summary["mapping_csv"] = str(mapping_csv_path)
        summary["sources"].append(source_summary)

    summary_path = write_summary_json(output_root, summary)
    summary["summary_json"] = str(summary_path)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
