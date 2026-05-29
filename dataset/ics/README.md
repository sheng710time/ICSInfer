# ICS Dataset Placement

The external ICS dataset is not included in this repository. To run the project,
place the dataset files under this directory using the expected structure below.
The code uses project-relative paths, so no absolute path configuration is
required after the files are copied into place.

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

For the standard training/evaluation workflow, place training pcaps in the
`train/` subdirectory and place evaluation pcaps directly under the protocol
directory. If a `train/` subdirectory is not present, the code falls back to the
pcap files directly under the protocol directory.

The device information CSV files should follow the unified schema used by this
project:

```text
id,ip,port,vendor,product_code,product_name,model_name,vendor_label,type_label,model_label,valid
```

After the files are placed in this layout, the training and evaluation scripts
can be run directly from the project root.
