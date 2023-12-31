import pandas as pd
import ipaddress
import sys
from intervaltree import Interval, IntervalTree
import geoip2.database

def count_ips_in_cidr(cidr):
    try:
        return ipaddress.ip_network(cidr, strict=False).num_addresses
    except ValueError:
        return 0

def validate_cidr(cidr, entity):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if not network.is_global:
            return False, "Non-public IP", count_ips_in_cidr(cidr)
        if entity == '' or pd.isna(entity):
            return False, "Missing Entity Name", count_ips_in_cidr(cidr)
        return True, "", count_ips_in_cidr(cidr)
    except ValueError as e:
        return False, str(e), 0

def lookup_asn_info(cidr, reader, error_log):
    try:
        start_ip = ipaddress.ip_network(cidr, strict=False)[0].exploded
        response = reader.asn(start_ip)
        return response.autonomous_system_number, response.autonomous_system_organization
    except Exception as e:
        error_log.append((cidr, str(e)))
        return None, None

def read_and_validate_csv(csv_path):
    try:
        cidr_df = pd.read_csv(csv_path)
        if 'CIDR' not in cidr_df.columns or 'Entity' not in cidr_df.columns:
            raise ValueError("CSV file must contain 'CIDR' and 'Entity' columns")
        return cidr_df
    except FileNotFoundError:
        print(f"Error: File '{csv_path}' not found.")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

def detect_overlaps(valid_cidrs, cidr_to_entity):
    overlap_details = []
    tree = IntervalTree()
    for cidr, num_ips in valid_cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        overlapping = tree[network.network_address.packed:network.broadcast_address.packed]
        if overlapping:
            for interval in overlapping:
                if interval.data != cidr and interval.data in cidr_to_entity:
                    overlap_details.append((cidr, cidr_to_entity.get(cidr, ''), interval.data, cidr_to_entity[interval.data], num_ips))
        tree[network.network_address.packed:network.broadcast_address.packed] = cidr
    return overlap_details

def perform_asn_lookups(valid_cidrs, db_path, cidr_to_entity):
    asn_details = {}
    error_log = []
    with geoip2.database.Reader(db_path) as reader:
        for cidr, _ in valid_cidrs:
            if cidr in cidr_to_entity:
                asn, org = lookup_asn_info(cidr, reader, error_log)
                if asn:
                    if asn not in asn_details:
                        asn_details[asn] = {'org': org, 'count': 0}
                    asn_details[asn]['count'] += 1
    return asn_details, error_log

def print_summary(total_ips, valid_cidrs, error_details, overlap_details, asn_details):
    total_valid_ips = sum(num_ips for _, num_ips in valid_cidrs)
    error_ips = sum(num_ips for errors in error_details.values() for _, num_ips in errors if isinstance(num_ips, int))
    error_percentage = (error_ips / total_ips) * 100 if total_ips > 0 else 0

    print(f"Total IP addresses in original file: {total_ips}")
    print(f"Total valid IP addresses after validation: {total_valid_ips}")
    print(f"Percentage of IP addresses removed due to errors: {error_percentage:.2f}%")

    for error_type, errors in error_details.items():
        print(f"{error_type}: {len(errors)}")
    
    print(f"Overlapping CIDRs: {len(overlap_details)}")
    print(f"Distinct ASNs: {len(asn_details)}\n")

    print("\n--- Distinct ASNs ---")
    for asn, details in asn_details.items():
        print(f"ASN: {asn}, Name: {details['org']}, Count: {details['count']}")


    print("\n--- Overlapping CIDRs with Entities ---")
    for cidr1, entity1, cidr2, entity2, _ in overlap_details:
        print(f"  {cidr1} ({entity1}) overlaps with {cidr2} ({entity2})")

    print("\n--- Errors ---")
    for error_type, errors in error_details.items():
        for cidr, num_ips in errors:
            print(f"  {cidr}: {error_type}")

def main(csv_file_path, db_path):
    cidr_df = read_and_validate_csv(csv_file_path)
    total_ips = sum(count_ips_in_cidr(cidr) for cidr in cidr_df['CIDR'])

    valid_cidrs = []
    error_details = {}
    cidr_to_entity = {row['CIDR']: row['Entity'] for _, row in cidr_df.iterrows() if 'Entity' in row and row['Entity']}

    for _, row in cidr_df.iterrows():
        cidr, entity = row['CIDR'], row.get('Entity', '')
        is_valid, error, num_ips = validate_cidr(cidr, entity)
        if not is_valid:
            error_details.setdefault(error, []).append((cidr, num_ips))
        else:
            valid_cidrs.append((cidr, num_ips))

    overlap_details = detect_overlaps(valid_cidrs, cidr_to_entity)
    asn_details, asn_errors = perform_asn_lookups(valid_cidrs, db_path, cidr_to_entity)
    error_details.setdefault("ASN Lookup Errors", []).extend(asn_errors)

    print_summary(total_ips, valid_cidrs, error_details, overlap_details, asn_details)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script_name.py <csv_file_path> <mmdb_file_path>")
        sys.exit(1)

    csv_file_path = sys.argv[1]
    db_path = sys.argv[2]

    main(csv_file_path, db_path)
