# ICSInfer

ICSInfer is the artifact for **ICSInfer: Device Model Identification for
Internet-Facing Industrial Control System Devices**. It implements the
training and inference pipeline for identifying the device models of
Internet-facing industrial control system (ICS) devices from packet sequences
collected through repeated probing interactions.

## Repository Layout

```text
ICSInfer/
  dataset/
    ics/                  External ICS dataset placeholder and instructions
    honeypot/             Honeypot metadata and pcaps
    shodan/               Shodan metadata and pcaps
  source/
    basis/                Packet parsing, filtering, and feature extraction
    config/               Project-relative path and global parameter settings
    semantic_identification/
      semantic_identification_train.py
      semantic_identification_normalization.py
      semantic_identification_train_defense.py
      semantic_identification_normalization_defense.py
      semantic_temporal_state_model_state.py
    others/               Analysis and utility scripts
  requirements.txt
  environment.yml
```

All runtime paths are derived from the project root in
`source/config/config.py`; no machine-specific absolute paths are required.

## Environment

The recommended environment uses Python 3.12.

```bash
conda env create -f environment.yml
conda activate ICSInfer
```

Alternatively:

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Dataset Placement

The external ICS dataset is not included in this repository. Place it under
`dataset/ics/` following the structure described in
`dataset/ics/README.md`.

Expected ICS layout:

```text
dataset/
  ics/
    modbus_device_information.csv
    s7_device_information.csv
    enip_device_information.csv
    modbus/
      train/
        *.pcap
      *.pcap
    s7/
      train/
        *.pcap
      *.pcap
    enip/
      train/
        *.pcap
      *.pcap
```

The CSV schema is:

```text
id,ip,port,vendor,product_code,product_name,model_name,vendor_label,type_label,model_label,valid
```

Training pcaps are read from `dataset/ics/<protocol>/train/` when that
directory exists; otherwise the code falls back to
`dataset/ics/<protocol>/*.pcap`. Honeypot and Shodan pcaps are read from
`dataset/honeypot/<protocol>/` and `dataset/shodan/<protocol>/`.

## Common Workflows

The main scripts are configured through variables in their `if __name__ ==
"__main__"` blocks. Edit `protocol`, `region`, `start_file_index`,
`file_number`, and related settings there before running a script.

Train state-based device signatures:

```bash
python source/semantic_identification/semantic_identification_train.py
```

Run identification/evaluation:

```bash
python source/semantic_identification/semantic_identification_normalization.py
```

Run defense training/evaluation variants:

```bash
python source/semantic_identification/semantic_identification_train_defense.py
python source/semantic_identification/semantic_identification_normalization_defense.py
```

## Outputs

Generated model, prediction, and evaluation CSV files are written under:

```text
results/ICSInfer_analysis/
```

The output subdirectory is usually grouped by protocol, for example
`results/ICSInfer_analysis/enip/`.
