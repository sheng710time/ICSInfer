"""
Encoding: UTF-8
Description:
"""
from pathlib import Path


PROJECT_NAME = "ICSInfer"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_ROOT = PROJECT_ROOT / "dataset"
RESULTS_ROOT = PROJECT_ROOT / "results"
ANALYSIS_DIR_NAME = f"{PROJECT_NAME}_analysis"
ANALYSIS_ROOT = RESULTS_ROOT / ANALYSIS_DIR_NAME
SUPPORTED_PROTOCOLS = {"modbus", "s7", "enip"}


def require_supported_protocol(protocol: str) -> None:
    if protocol not in SUPPORTED_PROTOCOLS:
        supported = ", ".join(sorted(SUPPORTED_PROTOCOLS))
        raise ValueError(f"Unsupported protocol: {protocol}. Supported protocols: {supported}.")


def require_existing_file(file_path: str, description: str) -> None:
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Missing {description}: {path}")


def require_existing_directory(directory_path: str, description: str) -> None:
    path = Path(directory_path)
    if not path.is_dir():
        raise FileNotFoundError(f"Missing {description}: {path}")


def project_path(*parts) -> str:
    return str(PROJECT_ROOT.joinpath(*parts))


def dataset_path(*parts) -> str:
    return str(DATASET_ROOT.joinpath(*parts))


def results_path(*parts, create_parent: bool = False) -> str:
    path = RESULTS_ROOT.joinpath(*parts)
    if create_parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)


def analysis_file(file_name: str, create_parent: bool = True) -> str:
    parts = str(file_name).replace("\\", "/").split("/")
    relative_path = Path(*parts)
    if relative_path.suffix != ".csv":
        relative_path = relative_path.with_suffix(".csv")
    path = ANALYSIS_ROOT / relative_path
    if create_parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)


def protocol_device_info_file(protocol: str) -> str:
    return dataset_path("ics", f"{protocol}_device_information.csv")


def source_device_info_file(protocol: str, source: str) -> str:
    return dataset_path(source, f"{protocol}_{source}_valid.csv")


def normalize_pcap_stem(file_stem: str) -> str:
    normalized_stem = file_stem.replace("_au_", "_")
    if normalized_stem.endswith("_au"):
        normalized_stem = normalized_stem[:-3]
    return normalized_stem


def pcap_stem_candidates(file_stem: str) -> list[str]:
    candidates = []
    for stem in (normalize_pcap_stem(file_stem), file_stem):
        if stem not in candidates:
            candidates.append(stem)
        if stem.endswith("_filtered"):
            unfiltered_stem = stem.removesuffix("_filtered")
            if unfiltered_stem not in candidates:
                candidates.append(unfiltered_stem)
    return candidates


def source_pcap_file(protocol: str, source: str, file_stem: str) -> str:
    candidates = [DATASET_ROOT / source / protocol / f"{stem}.pcap" for stem in pcap_stem_candidates(file_stem)]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return str(candidates[0])


def protocol_pcap_directory(protocol: str, region: str, subset: str | None = None) -> str:
    base_candidates = [
        DATASET_ROOT / "ics" / protocol,
        DATASET_ROOT / "pcap" / f"{protocol}_{region}",
    ]
    candidates = base_candidates
    if subset:
        candidates = [candidate / subset for candidate in base_candidates] + base_candidates
    for candidate in candidates:
        if candidate.exists() and any(candidate.glob("*.pcap")):
            return str(candidate)
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return str(base_candidates[0])


def protocol_pcap_file(protocol: str, region: str, file_stem: str, subset: str | None = None) -> str:
    base_directories = [
        DATASET_ROOT / "ics" / protocol,
        DATASET_ROOT / "pcap" / f"{protocol}_{region}",
    ]
    directories = base_directories
    if subset:
        directories = [directory / subset for directory in base_directories] + base_directories
    candidates = []
    for directory in directories:
        for stem in pcap_stem_candidates(file_stem):
            candidates.append(directory / f"{stem}.pcap")
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return str(candidates[0])


# Hyperparameter DM_Bias
GLOBAL_DM_BIAS = 0.75

# Hyperparameter DL_Ratio
GLOBAL_DL_RATIO = 0.75

# Hyperparameter, the alignment threshold, Tali
GLOBAL_TALI = 0.8   # GLOBAL_TALI = 1.0 Disable Alignment Component

# Device match threshold
GLOBAL_DM_Score = 0.5

# Operation match threshold
GLOBAL_OPERATION_MATCH = 0.2

# Packet match threshold
GLOBAL_PACKET_MATCH = 1.0

