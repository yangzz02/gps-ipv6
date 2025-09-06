# GPS-IPv6

GPS-IPv6 is an enhanced version of the original [GPStool](https://github.com/stanford-esrg/gps) with extended IPv6 support for large-scale Internet service discovery.

## Prerequisites

### Computational Requirements

- Python 3.7+
- Google [BigQuery](http://bigquery.cloud.google.com) Account​​ (with billing setup) and [google cloud command line](https://cloud.google.com/sdk/docs/install)
- ​​Internet Scanning Tools​​:
    - [LZR](https://github.com/stanford-esrg/lzr) or [LZR-IPv6](https://github.com/yangzz02/lzr-ipv6)
    - [ZMap](https://github.com/zmap/zmap) or [XMap](https://github.com/idealeer/xmap)
    - [ZGrab](https://github.com/zmap/zgrab2)
- Storage​​: 1TB+ disk space recommended

### Cost Estimate

-  BigQuery usage typically costs <$1 per run (if intermediate tables are promptly deleted)
-  Users are responsible for their own Google Cloud billing

## Quick Start

### Configuration
Edit config.iniwith your settings:
```
[BigQuery]
project_id = your-project-id
dataset_id = your-dataset
table_name = seed_scan_data

[GPS]
output_dir = /path/to/output
min_hitrate = 0.01
pre_filt_seed = False
```

### Seed Scan Format
GPS supports two input formats:

1. ​​Raw LZR scan output​​ (when Pre_Filt_Seed=False)

2. ​​Structured schema​​:
```
ip (string), p (port number- integer), asn (integer), data (string),\
fingerprint (protocol - string), w (tcp window size-integer).
```

### Running

#### Phase 1 - Initial Prediction:
```bash
python gps.py first
```
Outputs: Subnet and port recommendations for initial scanning
#### Phase 2 - Prior Results Processing:
```bash
python scripts/prior_scan.py
```

#### ​​Phase 3 - Remaining Services Prediction:​​
```bash
python gps.py remaining
```
Outputs: Comprehensive service list for full scanning

### Cleanup
Manually delete BigQuery tables after completion:
```
# Check your BigQuery console and remove GPS-generated tables
bq rm -t your-project:your-dataset.table_name
```
