# CIDR Block Analysis Tool

## Overview
This script is designed for analyzing CIDR (Classless Inter-Domain Routing) blocks from a CSV file. It performs validations on the CIDR blocks, identifies overlaps, conducts ASN (Autonomous System Number) lookups, and provides a detailed summary. This tool is especially useful for network management and analysis.

## Prerequisites
- **Python 3.x**: Ensure Python 3 is installed.
- **Required Python Libraries**: 
  - `Pandas`
  - `IntervalTree`
  - `GeoIP2`

  These can be installed using pip:
  ```bash
  pip install pandas intervaltree geoip2
- **MaxMind GeoLite2 ASN Database**: Download the database from [MaxMind](https://www.maxmind.com/en/geoip2-databases). Registration may be required.

## CSV File Format
The script expects a CSV file with the following structure:
- `CIDR`: The CIDR block (e.g., `192.168.1.0/24`).
- `Entity`: The associated entity or organization.

Example:
```csv 
CIDR,Entity
192.168.1.0/24,Company A
192.168.2.0/24,Company B
```

## Validation Criteria
1. **CIDR Format**: Validates the correctness of the CIDR notation.
2. **Public IP Check**: Ensures the CIDR blocks represent public IP addresses.
3. **Entity Association**: Checks that each CIDR block is associated with an entity. Missing entities are flagged.
4. **Overlap Detection**: Identifies and reports overlapping CIDR blocks.

## Usage
Run the script with the CSV file and the MaxMind database file as arguments:

`python script_name.py <path_to_csv_file> <path_to_mmdb_file>`

Replace `script_name.py` with the name of your script, `<path_to_csv_file>` with your CSV file's path, and `<path_to_mmdb_file>` with the path to the MaxMind database file.

Example:

`python script_name.py mydata.csv GeoLite2-ASN.mmdb`


## Output
The script provides a summary including:
- Total IPs in the original file.
- Number of valid IPs after validation.
- Percentage of IPs removed due to errors.
- Syntax errors, entity name errors, non-public IPs.
- Overlapping CIDR blocks with entity details.
- Distinct ASNs with names and counts.

## Contact
For any inquiries or feedback regarding this script, feel free to reach out.


