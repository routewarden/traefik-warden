#!/usr/bin/env python3
"""Convert local GeoLite2/GeoIP2 ASN Blocks CSV files to RouteWarden JSON.

Usage: python3 scripts/build-asn-db.py -o asn.json IPv4.csv IPv6.csv
Input columns: network, autonomous_system_number. No network access is used.
"""
import argparse
import csv
import ipaddress
import json
import os
from pathlib import Path
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inputs', nargs='+', type=Path)
    parser.add_argument('-o', '--output', required=True, type=Path)
    args = parser.parse_args()
    origins = {}
    database = {}
    try:
        for source in args.inputs:
            with source.open(encoding='utf-8-sig', newline='') as stream:
                reader = csv.DictReader(stream)
                if not {'network', 'autonomous_system_number'}.issubset(reader.fieldnames or []):
                    raise ValueError(f'{source}: expected network and autonomous_system_number columns')
                for line, row in enumerate(reader, 2):
                    network = str(ipaddress.ip_network(row['network'], strict=True))
                    number = row['autonomous_system_number']
                    if not number.isascii() or not number.isdigit() or not 1 <= int(number) <= 4294967295:
                        raise ValueError(f'{source}:{line}: invalid ASN {number!r}')
                    number = str(int(number))
                    if network in origins:
                        if origins[network] != number:
                            raise ValueError(f'{source}:{line}: conflicting origin for {network}')
                        continue
                    origins[network] = number
                    database.setdefault(number, []).append(network)
        if not database:
            raise ValueError('input has no ASN routes')
        # Atomic replacement keeps a failed conversion from damaging the active snapshot.
        output = args.output.resolve()
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=output.parent, delete=False) as stream:
            temp_path = Path(stream.name)
            try:
                json.dump(database, stream, sort_keys=True, separators=(',', ':'))
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
            except BaseException:
                temp_path.unlink(missing_ok=True)
                raise
        try:
            os.replace(temp_path, output)
        finally:
            temp_path.unlink(missing_ok=True)
    except (OSError, ValueError, KeyError) as err:
        parser.error(str(err))
    print(f'Wrote {len(origins)} prefixes for {len(database)} ASNs to {output}')


if __name__ == '__main__':
    main()
