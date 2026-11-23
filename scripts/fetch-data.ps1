# Downloads reference data into data/ (git-ignored).
#   pwsh scripts/fetch-data.ps1
# - oui.csv: IEEE MA-L (OUI) registry, used for MAC/BSSID vendor lookup.
# - company_identifiers.yaml, member_uuids.yaml, service_uuids.yaml: Bluetooth SIG
#   assigned numbers, used to name BLE manufacturers and services.
$ErrorActionPreference = 'Stop'
$data = Join-Path $PSScriptRoot '..\data'
New-Item -ItemType Directory -Force $data | Out-Null
$ua = 'Mozilla/5.0 (net-analysis data fetch)'
$sig = 'https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers'

$files = [ordered]@{
    'oui.csv'                  = 'https://standards-oui.ieee.org/oui/oui.csv'
    'company_identifiers.yaml' = "$sig/company_identifiers/company_identifiers.yaml"
    'member_uuids.yaml'        = "$sig/uuids/member_uuids.yaml"
    'service_uuids.yaml'       = "$sig/uuids/service_uuids.yaml"
}
foreach ($name in $files.Keys) {
    $out = Join-Path $data $name
    Invoke-WebRequest -Uri $files[$name] -OutFile $out -UserAgent $ua
    $lines = (Get-Content $out | Measure-Object -Line).Lines
    "Saved {0,6} lines to {1}" -f $lines, (Resolve-Path $out).Path
}
