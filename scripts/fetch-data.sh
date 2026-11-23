#!/usr/bin/env sh
# Downloads reference data into data/ (git-ignored).
#   sh scripts/fetch-data.sh
# - oui.csv: IEEE MA-L (OUI) registry, used for MAC/BSSID vendor lookup.
# - company_identifiers.yaml, member_uuids.yaml, service_uuids.yaml: Bluetooth SIG
#   assigned numbers, used to name BLE manufacturers and services.
set -eu
dir="$(cd "$(dirname "$0")/.." && pwd)/data"
mkdir -p "$dir"
ua="Mozilla/5.0 (net-analysis data fetch)"
sig="https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers"

fetch() {
    curl -fsSL -A "$ua" -o "$dir/$1" "$2"
    echo "Saved $(wc -l < "$dir/$1") lines to $dir/$1"
}

fetch oui.csv https://standards-oui.ieee.org/oui/oui.csv
fetch company_identifiers.yaml "$sig/company_identifiers/company_identifiers.yaml"
fetch member_uuids.yaml "$sig/uuids/member_uuids.yaml"
fetch service_uuids.yaml "$sig/uuids/service_uuids.yaml"
